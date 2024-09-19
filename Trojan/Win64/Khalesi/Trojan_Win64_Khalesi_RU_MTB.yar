
rule Trojan_Win64_Khalesi_RU_MTB{
	meta:
		description = "Trojan:Win64/Khalesi.RU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 40 48 8b 1d ?? ?? ?? ?? 0f 29 74 24 30 0f 29 7c 24 20 80 3b 00 75 1a 41 b8 b6 23 00 00 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? ff 15 } //1
		$a_01_1 = {49 6d 67 75 69 20 44 65 73 69 67 6e 20 56 33 5c 49 6d 67 75 69 20 44 65 73 69 67 6e 20 56 33 5c 49 6d 67 75 69 20 44 65 73 69 67 6e 20 56 33 5c 65 78 61 6d 70 6c 65 73 5c 45 78 65 } //1 Imgui Design V3\Imgui Design V3\Imgui Design V3\examples\Exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}