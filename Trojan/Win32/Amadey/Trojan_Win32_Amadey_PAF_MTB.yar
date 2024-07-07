
rule Trojan_Win32_Amadey_PAF_MTB{
	meta:
		description = "Trojan:Win32/Amadey.PAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b d0 88 95 90 01 04 0f b6 8d 90 01 04 f7 d9 88 8d 90 01 04 0f b6 95 90 01 04 83 ea 6f 88 95 90 01 04 0f b6 85 90 01 04 f7 d0 88 85 90 01 04 0f b6 8d 90 01 04 03 8d fc f7 ff ff 88 8d 90 01 04 0f b6 95 90 01 04 f7 da 88 95 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}