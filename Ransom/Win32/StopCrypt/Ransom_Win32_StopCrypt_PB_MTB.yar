
rule Ransom_Win32_StopCrypt_PB_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 bb 52 c0 5d 81 6d ?? 36 dd 96 53 81 45 ?? 3a dd 96 53 8b 4d dc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}