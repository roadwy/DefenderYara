
rule Ransom_Win32_StopCrypt_PCB_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8b 44 24 ?? 03 c5 33 c1 83 3d [0-08] c7 05 [0-0a] 89 4c 24 ?? 89 44 24 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}