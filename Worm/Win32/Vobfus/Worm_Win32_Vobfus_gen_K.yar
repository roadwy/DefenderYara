
rule Worm_Win32_Vobfus_gen_K{
	meta:
		description = "Worm:Win32/Vobfus.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {4a f5 02 00 00 00 b2 aa f5 02 00 00 00 aa 6c ?? ff 0b ?? 00 0c 00 31 ?? ff } //1
		$a_03_1 = {f4 02 eb 6b 74 ff eb fb cf e8 c4 fd 69 ?? ?? fc 46 71 ?? ?? 00 0e 6c ?? ?? f5 00 00 00 00 cc 1c } //1
		$a_03_2 = {f4 58 fc 0d [0-0a] f4 5b fc 0d 90 08 01 80 f4 50 fc 0d 90 08 02 30 f3 c3 00 fc 0d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}