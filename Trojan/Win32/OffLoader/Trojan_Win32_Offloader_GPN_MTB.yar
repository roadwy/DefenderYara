
rule Trojan_Win32_Offloader_GPN_MTB{
	meta:
		description = "Trojan:Win32/Offloader.GPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_80_0 = {64 69 72 74 69 6e 73 74 72 75 6d 65 6e 74 2e 78 79 7a 2f 70 65 2f 62 75 69 6c 64 2e 70 68 70 } //dirtinstrument.xyz/pe/build.php  1
	condition:
		((#a_80_0  & 1)*1) >=1
 
}