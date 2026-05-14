
rule Trojan_Win64_Zusy_AHB_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 57 c8 f3 0f 7f 4c 0f ?? f3 0f 6f 44 0f ?? 66 0f 6f ca 0f 57 c8 f3 0f 7f 4c 0f ?? 48 83 c1 ?? 48 3b c8 72 } //30
		$a_01_1 = {4c 6f 61 64 52 65 61 6c 4c 69 62 63 75 72 6c 3a 20 53 55 43 43 45 53 53 20 2d 20 44 4c 4c 20 6c 6f 61 64 65 64 } //20 LoadRealLibcurl: SUCCESS - DLL loaded
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}