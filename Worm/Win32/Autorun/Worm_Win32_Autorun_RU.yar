
rule Worm_Win32_Autorun_RU{
	meta:
		description = "Worm:Win32/Autorun.RU,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 54 68 75 6d 62 73 2e 65 78 65 } //1 \Thumbs.exe
		$a_01_1 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_01_2 = {73 68 65 6c 6c 5c 50 52 4d 5c 63 6f 6d 6d 61 6e 64 20 3d 20 54 68 75 6d 62 73 2e 65 78 65 20 2d 73 74 61 72 74 } //1 shell\PRM\command = Thumbs.exe -start
		$a_01_3 = {48 69 2c 20 49 27 6d 20 76 69 72 75 73 } //1 Hi, I'm virus
		$a_01_4 = {46 6f 72 6d 61 74 20 43 3a 20 5b 2d 5d 20 2e } //1 Format C: [-] .
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}