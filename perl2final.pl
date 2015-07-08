#!/usr/bin/perl
use strict;
use warnings;

my $count = 0;
my $order;
my $first_line;
my (@ip_directs, @host_directs);
my (@denys, @allows);

while (defined (my $line = <>)) 
{
  chomp $line;
  
  if ($count == 0)
  {
  $first_line = $line;
  unless ($line =~ /\Aorder/)
  {
    die "No order directive in input\n"
  }
  $order = parse_order($first_line);
  }
  
  if ($count == 1 && $line =~ /\A(order)/)
  {
    $order = parse_order($line);
    print "Multiple ORDER directives\n";
  } 
  
  if ($line =~ /\Aallow/ || $line =~ /\Adeny/)
  {
    parse_directs($line);
  } 
  
  $count++;
}

run();
sub run 
{
  for (inter_face(); my $input = <STDIN>; inter_face())
  {
    chomp $input;
    set_response($input);
  }
}

sub inter_face
{
  print "Input address to test: ";
}

sub parse_order
{
  my $line = shift;
  my ($order, $alternatives) = split('\s', $line);
  my ($first, $second) = split(',', $alternatives);
  return $first;
}

sub parse_directs
{
  my $line = shift;
  $line =~ /\A(\w+)\sfrom\s(.+)/ or die "wrong form\n";
  my $direct = $1;
  
  if ($2 =~ /\A(\d+.+)/)
  {
    push(@ip_directs, $line);
  }
  elsif ($2 =~ /\A(\w+.+)/)
  {
    push(@host_directs, $line);
  }  
}

sub set_response 
{
  my $string = shift;
  exit if $string =~ /\Aquit/i;
 
  if ($order eq "allow")
  {
    my ($allow, $deny) = do_match($string);
    
	  if (($allow) && (!$deny)) 
	  {
	    print "ALLOWED\n";
	  }
	  elsif (($allow) && ($deny))
	  {
	    print "REJECTED\n";
	  }
	  else
	  {
	    print "REJECTED\n";
	  }
    
  }
  elsif ($order eq "deny")
  {
    my ($allow, $deny) = do_match($string);
    
    	 if ((!$allow) && ($deny)) 
	  {
	    print "REJECTED\n";
	  }
	  elsif (($allow) && ($deny))
	  {
	    print "ALLOWED\n";
	  }
	  else
	  {
	    print "ALLOWED\n";
	  }
    
  }
}

sub do_match
{
  my $string = shift;
  my $allow = 0;
  my $deny = 0;
  
    if (@ip_directs)
    {
      	  parse_alternatives(@ip_directs);
          my @input_split = split('\.', $string);
                   
          while (@input_split)
          {
            my $input = join(".", @input_split);
            
            foreach my $directive(@allows)
            {
              
              if ($directive =~ /\A(\w+)\sfrom\s(.+)/)
              {
                
                if ($input =~ /\A$2\z/)
                {
                  
                  $allow++;
                }
              }
            }
            foreach my $directive(@denys)
            {
              if ($directive =~ /\A(\w+)\sfrom\s(.+)/)
              {
                
                if ($input =~ /\A$2\z/)
                {
                  
                  $deny++;
                }
              }
            }
            my $input_count = @input_split;
            splice @input_split, $input_count - 1, 1;
          }
    }
    elsif (@host_directs)
    {
          
          parse_alternatives(@host_directs);
	  my @input_split = split('\.', $string);
	  while (@input_split)
	  {
	    my $input = join(".", @input_split);
	    
	    foreach my $directive (@allows)
	    {
	       if ($directive =~ /\A(\w+)\sfrom\s(.+)/)
	       {
	         if ($input =~ /\A$2\z/)
	         {
	           $allow++;
	         }
	         
	       }
	    } 
	    foreach my $directive (@denys)
	    {
	      if ($directive =~ /\A(\w+)\sfrom\s(.+)/)
	      {	        
	        if ($input =~ /\A$2\z/)
	        {
	          $deny++;	          
	        }
	      }
	    }
	    splice @input_split, 0, 1;
	  }
	}
	return $allow, $deny;
}

sub parse_alternatives
{
  my @directs = @_;
  foreach my $directive (@directs) 
	  {
	    if ($directive =~ /\Adeny\sfrom\s.+/)
	    {
	      
	      push(@denys, $directive);
	    }
	    elsif ($directive =~ /\Aallow\sfrom\s.+/)
	    {
	      
	      push(@allows, $directive);
	    }
	  }
	  
}
