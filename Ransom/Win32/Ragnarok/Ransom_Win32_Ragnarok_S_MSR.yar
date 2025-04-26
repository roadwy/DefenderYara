
rule Ransom_Win32_Ragnarok_S_MSR{
	meta:
		description = "Ransom:Win32/Ragnarok.S!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 f1 8a 04 1a 88 04 3e 46 83 fe 40 90 13 e8 ?? ?? ff ff 33 d2 b9 3d 00 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}