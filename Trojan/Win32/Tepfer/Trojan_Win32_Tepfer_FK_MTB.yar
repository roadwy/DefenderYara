
rule Trojan_Win32_Tepfer_FK_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8b 85 ?? ?? ff ff 83 c0 64 89 85 ?? ?? ff ff 83 ad ?? ?? ff ff 64 8a 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 30 14 30 83 7d ?? 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}