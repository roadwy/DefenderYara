
rule TrojanDownloader_Win32_Bancos_AEW{
	meta:
		description = "TrojanDownloader:Win32/Bancos.AEW,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 2a 70 23 68 25 70 25 3f 2a 63 40 68 23 61 23 76 25 65 2a 3d 23 78 23 63 25 68 2a 61 40 76 23 65 25 26 25 75 2a 72 23 6c 23 3d } //1 .*p#h%p%?*c@h#a#v%e*=#x#c%h*a@v#e%&%u*r#l#=
		$a_01_1 = {0a 00 00 00 5c 69 64 73 79 73 2e 74 78 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}