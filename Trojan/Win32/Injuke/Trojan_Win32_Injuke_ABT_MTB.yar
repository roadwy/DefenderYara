
rule Trojan_Win32_Injuke_ABT_MTB{
	meta:
		description = "Trojan:Win32/Injuke.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 10 8b 45 f8 83 c0 04 89 45 f8 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 45 f8 3b 05 } //5
		$a_01_1 = {32 32 79 6c 6b 75 38 79 68 30 34 39 79 75 30 33 34 68 6b 6f 66 77 34 32 68 34 72 79 6a 30 32 67 39 34 30 67 39 76 72 67 68 77 30 38 } //5 22ylku8yh049yu034hkofw42h4ryj02g940g9vrghw08
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}