
rule Trojan_Linux_Slice_gen_A{
	meta:
		description = "Trojan:Linux/Slice.gen!A,SIGNATURE_TYPE_ELFHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 4f 54 49 43 45 20 25 73 20 3a 73 6c 69 63 65 20 3c 64 65 73 74 69 6e 61 74 69 6f 6e 3e 20 3c 6c 6f 77 70 6f 72 74 3e 20 3c 68 69 67 68 70 6f 72 74 3e 20 3c 73 65 63 73 3e } //4 NOTICE %s :slice <destination> <lowport> <highport> <secs>
		$a_01_1 = {50 52 49 56 4d 53 47 20 25 73 20 3a 73 79 6e 66 6c 6f 6f 64 69 6e 67 20 25 73 2e } //3 PRIVMSG %s :synflooding %s.
		$a_01_2 = {70 73 20 61 75 78 20 7c 20 67 72 65 70 20 2d 45 20 22 68 74 74 70 64 7c 6e 67 69 6e 78 7c 6c 73 77 73 7c 61 70 61 63 68 65 32 22 20 7c 20 77 63 20 2d 6c } //3 ps aux | grep -E "httpd|nginx|lsws|apache2" | wc -l
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3) >=10
 
}