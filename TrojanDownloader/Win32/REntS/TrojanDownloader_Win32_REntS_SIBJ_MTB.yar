
rule TrojanDownloader_Win32_REntS_SIBJ_MTB{
	meta:
		description = "TrojanDownloader:Win32/REntS.SIBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 c3 9f 88 e0 aa bb ?? ?? ?? ?? d1 c3 ba ?? ?? ?? ?? b9 ?? ?? ?? ?? d3 ca ba ?? ?? ?? ?? b9 ?? ?? ?? ?? d3 ca ba ?? ?? ?? ?? b9 ?? ?? ?? ?? d3 c2 ba ?? ?? ?? ?? 42 9f 88 27 47 b8 ?? ?? ?? ?? 48 ba ?? ?? ?? ?? b9 ?? ?? ?? ?? d3 ca 9f 88 e0 aa bb ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 9c 5a 88 17 47 ba ?? ?? ?? ?? d1 c2 ba ?? ?? ?? ?? 4a 9c 5a 88 17 47 bb ?? ?? ?? ?? b9 ?? ?? ?? ?? d3 c3 bb ?? ?? ?? ?? 43 9f 88 27 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}