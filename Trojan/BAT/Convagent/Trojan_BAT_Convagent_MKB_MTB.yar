
rule Trojan_BAT_Convagent_MKB_MTB{
	meta:
		description = "Trojan:BAT/Convagent.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 65 78 65 63 44 69 72 20 3d 20 24 64 6f 63 75 6d 65 6e 74 73 50 61 74 68 20 2b 20 22 5c 2e 5f 5f 63 6f 6e 66 69 67 5f } //12 $execDir = $documentsPath + "\.__config_
		$a_01_1 = {53 65 74 2d 49 74 65 6d 50 72 6f 70 65 72 74 79 20 2d 50 61 74 68 20 24 65 78 65 63 44 69 72 20 2d 4e 61 6d 65 20 61 74 74 72 69 62 75 74 65 73 20 2d 56 61 6c 75 65 20 28 5b 53 79 73 74 65 6d 2e 49 4f 2e 46 69 6c 65 41 74 74 72 69 62 75 74 65 73 5d 3a 3a 48 69 64 64 65 6e 29 } //8 Set-ItemProperty -Path $execDir -Name attributes -Value ([System.IO.FileAttributes]::Hidden)
		$a_01_2 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 24 65 78 65 63 44 69 72 } //5 Add-MpPreference -ExclusionPath $execDir
		$a_01_3 = {44 65 63 72 79 70 74 20 74 68 65 20 64 61 74 61 } //3 Decrypt the data
		$a_01_4 = {52 75 6e 20 74 68 65 20 70 61 79 6c 6f 61 64 } //2 Run the payload
	condition:
		((#a_01_0  & 1)*12+(#a_01_1  & 1)*8+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2) >=30
 
}