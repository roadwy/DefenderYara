
rule TrojanDownloader_BAT_Obfuse_PAEZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Obfuse.PAEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 22 70 61 79 6c 6f 61 64 2e 62 61 74 22 } //1 cmd.exe /c "payload.bat"
		$a_01_1 = {52 55 4e 50 52 4f 47 52 41 4d } //1 RUNPROGRAM
		$a_01_2 = {52 45 42 4f 4f 54 } //1 REBOOT
		$a_01_3 = {6d 73 64 6f 77 6e 6c 64 2e 74 6d 70 } //1 msdownld.tmp
		$a_01_4 = {77 65 78 74 72 61 63 74 2e 70 64 62 } //1 wextract.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}