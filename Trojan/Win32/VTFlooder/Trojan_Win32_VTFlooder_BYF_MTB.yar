
rule Trojan_Win32_VTFlooder_BYF_MTB{
	meta:
		description = "Trojan:Win32/VTFlooder.BYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 36 32 38 31 32 37 39 2e 79 6f 6c 6f 78 2e 6e 65 74 } //01 00  a6281279.yolox.net
		$a_01_1 = {56 4d 47 72 61 62 } //01 00  VMGrab
		$a_01_2 = {2f 76 74 61 70 69 2f 76 32 2f 66 69 6c 65 2f 73 63 61 6e } //01 00  /vtapi/v2/file/scan
		$a_01_3 = {34 64 31 65 65 31 34 61 33 31 39 31 62 61 31 61 66 64 65 35 32 36 31 33 32 36 64 63 64 37 65 38 31 37 39 33 61 66 61 63 62 36 61 61 37 65 34 36 64 30 62 34 36 37 62 63 36 65 62 63 64 33 36 37 } //00 00  4d1ee14a3191ba1afde5261326dcd7e81793afacb6aa7e46d0b467bc6ebcd367
	condition:
		any of ($a_*)
 
}