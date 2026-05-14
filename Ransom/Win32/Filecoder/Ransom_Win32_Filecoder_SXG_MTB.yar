
rule Ransom_Win32_Filecoder_SXG_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.SXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 8b fc c7 44 24 ?? 11 45 14 19 c7 44 24 ?? 19 81 0a 0a c7 44 24 ?? 1f 2d 3c 4b c7 44 24 ?? 5a 69 78 87 c7 44 24 ?? 96 a5 b4 c3 c7 44 24 ?? d2 e1 f0 0f c7 44 24 ?? 1e 2d 3c 4b c7 44 24 ?? 5a 69 78 87 } //20
		$a_03_1 = {48 63 fb 48 8d 54 24 ?? 48 c1 e7 0a 49 03 ff 48 8b cf e8 ?? ?? ?? ?? 85 c0 75 4d } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}