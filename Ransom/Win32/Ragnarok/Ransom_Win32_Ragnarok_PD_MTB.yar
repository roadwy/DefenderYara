
rule Ransom_Win32_Ragnarok_PD_MTB{
	meta:
		description = "Ransom:Win32/Ragnarok.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 fb 8b da 8b 95 f8 [0-04] 0f b6 84 1d ?? ?? ?? ?? 88 84 15 ?? ?? ?? ?? 88 8c 1d ?? ?? ?? ?? b9 06 00 00 00 0f b6 84 15 ?? ?? ?? ?? 33 d2 03 c6 f7 f1 0f b6 84 15 ?? ?? ?? ?? 30 87 ?? ?? ?? ?? 47 8b 85 f8 [0-04] 81 ff a6 10 00 00 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}