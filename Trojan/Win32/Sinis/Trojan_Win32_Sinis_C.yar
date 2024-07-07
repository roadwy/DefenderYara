
rule Trojan_Win32_Sinis_C{
	meta:
		description = "Trojan:Win32/Sinis.C,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 } //2 \Microsoft\Internet Explorer\Quick Launch
		$a_01_1 = {5c 6d 64 35 64 6c 6c 2e 64 6c 6c } //2 \md5dll.dll
		$a_01_2 = {63 72 79 6f 2d 75 70 64 61 74 65 2e 63 61 2f } //1 cryo-update.ca/
		$a_01_3 = {73 74 61 72 74 61 6c 69 61 6e 63 65 2e 69 6e 66 6f 2f } //1 startaliance.info/
		$a_01_4 = {64 72 69 76 65 72 75 70 64 73 65 72 76 65 72 73 2e 6e 65 74 2f } //1 driverupdservers.net/
		$a_01_5 = {2f 63 66 67 2f 75 70 64 2e 70 68 70 3f 69 64 3d } //1 /cfg/upd.php?id=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}