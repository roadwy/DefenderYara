
rule Adware_MacOS_Cimpli_A_MTB{
	meta:
		description = "Adware:MacOS/Cimpli.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 63 c5 48 8d 0d ?? ?? 02 00 8a 04 08 42 32 44 35 b0 88 45 98 4c 89 e7 48 8d 75 98 e8 ?? ?? fe ff 45 85 ed 41 8d 45 ff 41 0f 4e c7 49 ff c6 41 89 c5 49 83 fe 11 75 c8 } //1
		$a_01_1 = {31 2e 32 2e 31 31 } //1 1.2.11
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}