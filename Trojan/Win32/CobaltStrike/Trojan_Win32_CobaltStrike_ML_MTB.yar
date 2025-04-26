
rule Trojan_Win32_CobaltStrike_ML_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 38 31 d2 89 c8 01 cf 41 89 7d f0 bf 0d 00 00 00 f7 f7 8a 44 16 0c 8b 55 f0 30 02 eb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}