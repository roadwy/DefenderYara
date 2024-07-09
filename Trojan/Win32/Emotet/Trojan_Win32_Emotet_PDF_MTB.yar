
rule Trojan_Win32_Emotet_PDF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8d 4c 24 ?? 8a 94 14 ?? ?? ?? ?? 32 da 88 5d 00 } //1
		$a_81_1 = {72 43 4a 67 43 63 58 4d 77 66 66 32 4f 32 32 57 54 32 7a 39 38 38 73 61 66 59 72 78 55 62 68 46 6f } //1 rCJgCcXMwff2O22WT2z988safYrxUbhFo
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}