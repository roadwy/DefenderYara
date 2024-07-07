
rule TrojanDownloader_O97M_AgentTesla_PA_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.PA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 64 61 73 33 20 3d 20 22 74 22 20 2b 20 22 61 20 68 74 22 } //1 pdas3 = "t" + "a ht"
		$a_00_1 = {53 68 65 6c 6c 20 70 6b 6b 6b 6b } //1 Shell pkkkk
		$a_00_2 = {6f 6b 66 66 72 20 3d 20 22 61 6b 64 6b 61 73 64 6f 61 6b 73 64 64 64 77 69 64 } //1 okffr = "akdkasdoaksdddwid
		$a_00_3 = {6b 61 73 6b 64 6b 2e 68 69 73 73 73 73 61 } //1 kaskdk.hissssa
		$a_00_4 = {6b 6f 34 64 20 3d 20 22 74 70 3a 2f 2f 25 37 34 38 32 33 37 25 37 32 38 37 34 38 40 6a 2e 6d 70 2f 22 } //1 ko4d = "tp://%748237%728748@j.mp/"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}