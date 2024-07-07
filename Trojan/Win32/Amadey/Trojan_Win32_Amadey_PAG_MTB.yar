
rule Trojan_Win32_Amadey_PAG_MTB{
	meta:
		description = "Trojan:Win32/Amadey.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b ca 88 8d 90 01 04 0f b6 85 90 01 04 f7 d8 88 85 90 01 04 0f b6 8d 90 01 04 83 c1 15 88 8d 90 01 04 0f b6 95 90 01 04 f7 d2 88 95 90 01 04 0f b6 85 90 01 04 2b 85 74 ff ff ff 88 85 90 01 04 0f b6 8d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}