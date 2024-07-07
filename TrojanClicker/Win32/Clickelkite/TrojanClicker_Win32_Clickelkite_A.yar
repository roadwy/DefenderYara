
rule TrojanClicker_Win32_Clickelkite_A{
	meta:
		description = "TrojanClicker:Win32/Clickelkite.A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 69 6e 6b 6c 6f 67 2e 69 6c 69 6b 65 63 6c 69 63 6b 2e 63 6f 6d } //5 linklog.ilikeclick.com
		$a_01_1 = {49 6c 69 6b 65 43 6c 69 63 6b 2e 64 61 74 } //5 IlikeClick.dat
		$a_01_2 = {26 69 6c 63 5f 63 75 73 56 61 72 31 3d 26 74 61 72 67 65 74 5f 75 72 6c 3d } //5 &ilc_cusVar1=&target_url=
		$a_01_3 = {2f 64 69 72 65 63 74 41 70 70 55 70 64 61 74 65 2f } //5 /directAppUpdate/
		$a_01_4 = {54 6f 6f 6c 62 61 72 52 65 73 74 6f 72 65 2e 65 78 65 } //1 ToolbarRestore.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1) >=21
 
}