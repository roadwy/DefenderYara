
rule TrojanDownloader_Win32_Waski_XI_MTB{
	meta:
		description = "TrojanDownloader:Win32/Waski.XI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 8d 64 24 ?? 8b 52 ?? 83 3c 82 ?? 8d 04 4e 52 8b 16 4f 8b 07 47 33 d0 46 ff 0c 24 8a c6 46 aa 58 8b d0 85 c0 ?? ?? 8b 45 ?? 8b 55 ?? 8b f0 e2 dd 41 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}