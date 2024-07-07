
rule Trojan_Win32_Kuyonip_A{
	meta:
		description = "Trojan:Win32/Kuyonip.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {61 6e 64 61 70 6f 6e 64 61 79 65 6c 6c 61 72 61 73 6b 61 6c 6c 61 2e 61 73 69 61 } //1 andapondayellaraskalla.asia
		$a_00_1 = {31 32 37 2e 30 2e 30 2e 31 20 74 61 74 61 63 6f 6d 70 75 74 65 72 2e 63 6f 6d } //1 127.0.0.1 tatacomputer.com
		$a_00_2 = {31 32 37 2e 30 2e 30 2e 31 20 62 6c 61 63 6b 74 73 2e 69 6e } //1 127.0.0.1 blackts.in
		$a_02_3 = {2f 67 65 6e 65 72 69 63 2f 75 70 64 61 74 65 2f 75 70 64 61 74 65 2e 64 6c 6c 90 02 06 5c 75 70 64 61 74 65 2e 65 78 65 00 90 00 } //1
		$a_00_4 = {70 69 6e 6f 79 66 75 6b 75 74 68 6f } //1 pinoyfukutho
		$a_00_5 = {70 69 6e 6f 79 64 6f 6e 6b 75 74 68 6f } //1 pinoydonkutho
		$a_00_6 = {5c 72 65 62 65 78 2e 65 78 65 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}