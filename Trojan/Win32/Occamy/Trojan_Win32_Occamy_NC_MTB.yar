
rule Trojan_Win32_Occamy_NC_MTB{
	meta:
		description = "Trojan:Win32/Occamy.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb d8 ff 96 90 01 04 83 c7 04 8d 5e fc 31 c0 8a 07 47 09 c0 74 22 3c ef 90 00 } //5
		$a_01_1 = {4c 6d 6b 6d 65 6a 6d 7a } //1 Lmkmejmz
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}