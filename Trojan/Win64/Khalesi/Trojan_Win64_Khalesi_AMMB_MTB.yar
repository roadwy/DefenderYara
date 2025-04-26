
rule Trojan_Win64_Khalesi_AMMB_MTB{
	meta:
		description = "Trojan:Win64/Khalesi.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 39 cf 74 ?? 8d 45 01 99 f7 fe 4c 63 ea 42 0f b6 84 2c ?? ?? ?? ?? 4b 8d 0c 2a 4c 89 ed 44 01 e0 99 f7 fe 4c 63 f2 4b 8d 14 32 4d 89 f4 e8 ?? ?? ?? ?? 42 8a 8c 34 ?? ?? ?? ?? 42 02 8c 2c ?? ?? ?? ?? 0f b6 c9 8a 84 0c ?? ?? ?? ?? 41 30 01 49 ff c1 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}