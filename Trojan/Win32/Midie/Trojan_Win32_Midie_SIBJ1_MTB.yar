
rule Trojan_Win32_Midie_SIBJ1_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBJ1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {76 6d 73 6c 6f 61 6e 62 2e 64 6c 6c } //1 vmsloanb.dll
		$a_03_1 = {33 c9 85 db 74 ?? 8a 04 39 [0-20] 2c ?? [0-20] 04 ?? [0-20] 88 04 39 41 3b cb 72 ?? 6a 00 57 6a 00 ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}