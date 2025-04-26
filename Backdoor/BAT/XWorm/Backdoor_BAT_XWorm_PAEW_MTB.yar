
rule Backdoor_BAT_XWorm_PAEW_MTB{
	meta:
		description = "Backdoor:BAT/XWorm.PAEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {4f 00 78 00 79 00 4f 00 78 00 79 00 4f 00 72 00 6f 00 6e 00 2e 00 42 00 61 00 6c 00 74 00 61 00 7a 00 61 00 52 00 4f 00 72 00 69 00 6f 00 6e 00 } //2 OxyOxyOron.BaltazaROrion
		$a_01_1 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 33 00 31 00 39 00 5c 00 4d 00 53 00 42 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00 } //2 C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}