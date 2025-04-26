
rule Trojan_Win32_Amadey_CAQT_MTB{
	meta:
		description = "Trojan:Win32/Amadey.CAQT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 7c 24 0c 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 29 44 24 ?? ff 4c 24 1c 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}