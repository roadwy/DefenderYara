
rule Trojan_Win64_LummaStealer_AHB_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 10 48 8b 94 24 c0 00 00 00 32 04 0a 48 8b 94 24 00 01 00 00 88 04 0a 48 83 c1 ?? 48 8b 84 24 c8 00 00 00 } //30
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 73 5c 67 67 2e 74 78 74 } //20 Downloads\gg.txt
		$a_01_2 = {61 6e 74 69 64 65 74 65 63 74 22 5c 73 2a 3a 5c 73 2a 5c 7b 28 5b } //10 antidetect"\s*:\s*\{([
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}