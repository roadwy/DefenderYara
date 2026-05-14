
rule Trojan_BAT_AveMaria_KK_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 61 74 68 3d 25 54 65 4d 70 25 } //1 Path=%TeMp%
		$a_01_1 = {53 65 74 75 70 3d 62 64 74 68 67 66 78 74 72 2e 63 6d 64 } //2 Setup=bdthgfxtr.cmd
		$a_01_2 = {53 69 6c 65 6e 74 3d 31 } //3 Silent=1
		$a_01_3 = {62 64 74 68 67 66 78 74 72 2e 63 6d 64 } //4 bdthgfxtr.cmd
		$a_01_4 = {62 7a 73 66 76 64 66 76 2e 73 66 78 2e 65 78 65 20 2d 64 25 54 65 6d 70 25 20 2d 70 66 6e 6f 75 79 64 7a 61 6c 65 70 64 6e 6f 69 6f 69 68 6d 79 6a 66 6f 64 74 67 66 73 61 66 64 79 65 68 6f 66 78 76 66 6c 69 6e 6c 6e 61 66 75 67 79 66 48 62 67 6e 6d 65 47 52 68 76 71 78 73 64 } //5 bzsfvdfv.sfx.exe -d%Temp% -pfnouydzalepdnoioihmyjfodtgfsafdyehofxvflinlnafugyfHbgnmeGRhvqxsd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*4+(#a_01_4  & 1)*5) >=15
 
}