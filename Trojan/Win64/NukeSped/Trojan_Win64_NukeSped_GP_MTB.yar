
rule Trojan_Win64_NukeSped_GP_MTB{
	meta:
		description = "Trojan:Win64/NukeSped.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_81_0 = {64 73 74 76 64 74 74 2e 63 6f 2e 7a 61 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 } //5 dstvdtt.co.za/wp-content/plugins
		$a_81_1 = {63 6d 61 73 65 64 75 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 } //1 cmasedu.com/wp-content/plugins
		$a_81_2 = {62 6d 74 70 61 6b 69 73 74 61 6e 2e 63 6f 6d 2f 73 6f 6c 75 74 69 6f 6e 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 } //1 bmtpakistan.com/solution/wp-content/plugins
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=7
 
}