
rule Ransom_Win64_BlackByte_GB_MTB{
	meta:
		description = "Ransom:Win64/BlackByte.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 14 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 64 65 63 46 75 6e 63 } //1 main.decFunc
		$a_01_1 = {6d 61 69 6e 2e 45 6e 63 72 79 70 74 } //1 main.Encrypt
		$a_01_2 = {6d 61 69 6e 2e 41 65 73 32 35 36 45 6e 63 72 } //1 main.Aes256Encr
		$a_01_3 = {6d 61 69 6e 2e 44 65 6c 53 68 61 64 6f 77 73 } //1 main.DelShadows
		$a_01_4 = {6d 61 69 6e 2e 44 65 73 74 72 6f 79 } //1 main.Destroy
		$a_01_5 = {6d 61 69 6e 2e 47 72 61 6e 74 41 6c 6c } //1 main.GrantAll
		$a_01_6 = {6d 61 69 6e 2e 45 6e 61 62 6c 65 4c 6f 6e 67 50 61 74 68 73 } //1 main.EnableLongPaths
		$a_01_7 = {6d 61 69 6e 2e 47 65 6e 44 72 69 76 65 73 } //1 main.GenDrives
		$a_01_8 = {6d 61 69 6e 2e 43 68 65 63 6b 42 75 73 79 } //1 main.CheckBusy
		$a_01_9 = {6d 61 69 6e 2e 50 72 65 76 65 6e 74 53 6c 65 65 70 } //1 main.PreventSleep
		$a_01_10 = {6d 61 69 6e 2e 53 68 6f 77 4e 6f 74 65 } //1 main.ShowNote
		$a_01_11 = {6d 61 69 6e 2e 53 74 61 72 74 70 72 6f 63 } //1 main.Startproc
		$a_01_12 = {6d 61 69 6e 2e 45 6e 61 62 6c 65 4c 69 6e 6b } //1 main.EnableLink
		$a_01_13 = {6d 61 69 6e 2e 53 65 74 75 70 4b 65 79 } //1 main.SetupKey
		$a_01_14 = {6d 61 69 6e 2e 4d 6f 75 6e 74 44 72 69 76 65 73 } //1 main.MountDrives
		$a_01_15 = {6d 61 69 6e 2e 4b 69 6c 6c } //1 main.Kill
		$a_01_16 = {6d 61 69 6e 2e 53 74 6f 70 41 6c 6c 73 76 63 } //1 main.StopAllsvc
		$a_01_17 = {6d 61 69 6e 2e 45 6e 63 6f 64 65 } //1 main.Encode
		$a_01_18 = {6d 61 69 6e 2e 43 6c 65 61 72 52 65 63 79 63 6c 65 } //1 main.ClearRecycle
		$a_01_19 = {42 6c 61 63 6b 42 79 74 65 47 4f 2f 5f 63 67 6f 5f 67 6f 74 79 70 65 73 2e 67 6f } //3 BlackByteGO/_cgo_gotypes.go
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*3) >=22
 
}