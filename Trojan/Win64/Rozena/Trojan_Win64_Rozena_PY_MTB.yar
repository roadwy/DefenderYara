
rule Trojan_Win64_Rozena_PY_MTB{
	meta:
		description = "Trojan:Win64/Rozena.PY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 6d 7a 64 6a 6a 65 6b 71 63 73 65 62 74 26 61 78 31 78 68 72 7a 77 71 6a 75 6d 77 68 6c 75 61 61 6d 7a 64 6a 6a 65 6b 71 63 73 65 62 74 66 61 78 73 78 } //1 amzdjjekqcsebt&ax1xhrzwqjumwhluaamzdjjekqcsebtfaxsx
		$a_01_1 = {49 89 c0 41 83 e0 1f 42 32 0c 02 88 0c 03 48 83 c0 01 39 f0 72 b1 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5) >=6
 
}