
rule Trojan_Win32_Zusy_PGZM_MTB{
	meta:
		description = "Trojan:Win32/Zusy.PGZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f4 8b 45 08 01 d0 0f b6 10 8b 4d f4 8b 45 f0 01 c8 83 f2 35 88 10 83 45 f4 01 8b 45 f4 3b 45 0c 7c dc } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}