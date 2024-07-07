
rule Trojan_Win64_CobaltStrike_YAV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 14 09 48 8d 49 01 80 ea 0c 41 ff c0 88 51 ff 41 83 f8 0c 72 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}