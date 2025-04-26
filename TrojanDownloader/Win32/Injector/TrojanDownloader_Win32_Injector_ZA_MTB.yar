
rule TrojanDownloader_Win32_Injector_ZA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Injector.ZA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {da 20 17 0d 6a cc 49 53 fe 54 b2 1f 52 79 08 71 59 b3 64 44 d0 5a 8b 19 95 6e 09 58 2e 4e 70 4d 9b 89 46 cf a4 5a 3c c5 74 5a ed c6 d3 bf 40 5c 79 9c bd 47 23 9b 5e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}