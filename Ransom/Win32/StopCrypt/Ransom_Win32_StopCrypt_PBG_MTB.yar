
rule Ransom_Win32_StopCrypt_PBG_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {5d c3 c7 05 ?? ?? ?? ?? 88 61 4d 00 c3 c7 05 ?? ?? ?? ?? 88 61 4d 00 c3 c7 05 ?? ?? ?? ?? 88 61 4d 00 c3 c7 05 ?? ?? ?? ?? 88 61 4d 00 c3 c7 05 ?? ?? ?? ?? 88 61 4d 00 c3 c7 05 ?? ?? ?? ?? 88 61 4d 00 c3 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}