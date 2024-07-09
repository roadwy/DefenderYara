
rule Trojan_Win32_Glupteba_MLAA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MLAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 64 89 44 24 10 83 6c 24 10 64 8a 4c 24 10 8b 44 24 ?? 30 0c 30 83 bc 24 ?? ?? ?? ?? 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}