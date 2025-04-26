
rule Ransom_Win32_Trinity_ATR_MTB{
	meta:
		description = "Ransom:Win32/Trinity.ATR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d3 03 7d d8 c1 c2 10 03 ca 89 4d 08 33 4d c8 c1 c1 0c 03 d9 33 d3 89 5d ec 8b 5d 08 c1 c2 08 } //1
		$a_03_1 = {6a 0a 68 c1 00 00 00 6a 00 ff d7 8b f0 85 f6 0f 84 ?? ?? ?? ?? 56 6a 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}