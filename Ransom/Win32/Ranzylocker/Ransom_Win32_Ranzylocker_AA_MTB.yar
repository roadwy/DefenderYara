
rule Ransom_Win32_Ranzylocker_AA_MTB{
	meta:
		description = "Ransom:Win32/Ranzylocker.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 1c 08 41 3b ca 72 90 0a 25 00 a1 ?? ?? ?? ?? 33 c9 8b 55 ?? 89 45 ?? 85 d2 74 ?? 8b d8 83 7d ?? ?? 8d 45 ?? 0f 43 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}