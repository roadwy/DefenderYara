
rule TrojanDownloader_Win64_Tiny_CCIR_MTB{
	meta:
		description = "TrojanDownloader:Win64/Tiny.CCIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 01 c2 0f be 02 8b 55 ?? 31 d0 88 01 eb } //2
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 20 22 45 78 70 61 6e 64 2d 41 72 63 68 69 76 65 20 2d 46 6f 72 63 65 } //1 powershell -WindowStyle Hidden -Command "Expand-Archive -Force
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}