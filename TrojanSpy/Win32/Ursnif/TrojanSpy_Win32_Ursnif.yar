
rule TrojanSpy_Win32_Ursnif{
	meta:
		description = "TrojanSpy:Win32/Ursnif,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 69 64 65 5f 65 76 72 32 2e 70 64 62 } //1 hide_evr2.pdb
		$a_00_1 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 6e 00 65 00 77 00 5f 00 64 00 72 00 76 00 } //1 \DosDevices\new_drv
		$a_00_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 6e 00 65 00 77 00 5f 00 64 00 72 00 76 00 } //1 \Device\new_drv
		$a_01_3 = {0f 20 c0 0d 00 00 01 00 0f 22 c0 } //1
		$a_01_4 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}