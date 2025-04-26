
rule Trojan_Win32_Emotet_DSF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {25 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 45 00 8a 54 14 ?? 32 c2 88 45 00 } //1
		$a_81_1 = {38 67 70 64 70 65 31 47 68 5a 6e 44 6c 53 71 4e 39 49 31 6a 4d 53 66 76 77 33 77 4b 4e 33 } //1 8gpdpe1GhZnDlSqN9I1jMSfvw3wKN3
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}