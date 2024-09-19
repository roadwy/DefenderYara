
rule Trojan_Win32_Amadey_IIZ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.IIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 d4 31 18 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 45 d4 8b 45 ec 3b 45 d0 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}