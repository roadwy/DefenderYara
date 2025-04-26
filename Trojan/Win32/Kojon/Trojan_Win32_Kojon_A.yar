
rule Trojan_Win32_Kojon_A{
	meta:
		description = "Trojan:Win32/Kojon.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 70 6c 6f 69 74 5f 45 78 65 69 6e 66 65 63 74 } //1 ShellExploit_Exeinfect
		$a_01_1 = {41 00 6e 00 74 00 69 00 20 00 56 00 69 00 72 00 75 00 73 00 20 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 2e 00 6c 00 6e 00 6b 00 } //1 Anti Virus Option.lnk
		$a_01_2 = {5c 61 74 74 61 63 6b 5f 74 65 6d 70 5c } //1 \attack_temp\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}