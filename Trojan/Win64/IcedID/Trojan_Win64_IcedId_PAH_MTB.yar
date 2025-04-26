
rule Trojan_Win64_IcedId_PAH_MTB{
	meta:
		description = "Trojan:Win64/IcedId.PAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 65 72 40 77 78 45 76 74 48 61 6e 64 6c 65 72 40 40 55 45 41 41 58 50 45 41 56 31 40 40 5a } //1 ler@wxEvtHandler@@UEAAXPEAV1@@Z
		$a_01_1 = {3f 53 74 6f 70 40 77 78 54 69 6d 65 72 40 40 55 45 41 41 58 58 5a } //1 ?Stop@wxTimer@@UEAAXXZ
		$a_01_2 = {30 77 78 55 52 49 40 40 51 45 41 41 40 41 45 42 56 77 78 53 74 72 69 6e 67 40 40 40 5a } //1 0wxURI@@QEAA@AEBVwxString@@@Z
		$a_01_3 = {77 78 6d 73 77 33 31 33 75 64 5f 68 74 6d 6c 5f 76 63 5f 78 36 34 5f 63 75 73 74 6f 6d 2e 70 64 62 } //1 wxmsw313ud_html_vc_x64_custom.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}