
rule Worm_Win32_Phorpiex_S{
	meta:
		description = "Worm:Win32/Phorpiex.S,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {75 4e 6a 00 6a 00 6a 00 6a 11 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 56 e8 ?? ?? ?? ?? 6a 00 6a 02 6a 00 6a 56 e8 ?? ?? ?? ?? 6a 00 6a 02 6a 00 6a 11 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 0d } //1
		$a_01_1 = {54 43 68 61 74 52 69 63 68 45 64 69 74 00 } //1 䍔慨剴捩䕨楤t
		$a_01_2 = {69 6d 61 67 65 73 2e 70 68 70 3f } //1 images.php?
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}