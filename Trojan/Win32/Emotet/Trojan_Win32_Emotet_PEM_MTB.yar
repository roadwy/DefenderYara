
rule Trojan_Win32_Emotet_PEM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 07 0f b6 cb 03 c1 8b ce 99 f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08 } //1
		$a_81_1 = {30 35 61 4f 50 4a 73 41 73 35 33 50 46 76 62 77 58 6b 54 6b 77 76 4c 70 43 42 62 78 37 71 6b 76 6e 66 68 61 42 59 78 5a 45 73 76 } //1 05aOPJsAs53PFvbwXkTkwvLpCBbx7qkvnfhaBYxZEsv
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}