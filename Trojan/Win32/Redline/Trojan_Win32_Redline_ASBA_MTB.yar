
rule Trojan_Win32_Redline_ASBA_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e9 18 33 4d f4 89 4d f4 69 55 f4 ?? ?? ?? ?? 89 55 f4 69 45 fc ?? ?? ?? ?? 89 45 fc 8b 4d fc 33 4d f4 89 4d fc eb } //4
		$a_01_1 = {42 75 72 6e 20 69 6e 20 75 67 6c 79 20 46 49 52 45 21 } //1 Burn in ugly FIRE!
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}