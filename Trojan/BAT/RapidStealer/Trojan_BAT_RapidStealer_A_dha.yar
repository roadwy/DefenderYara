
rule Trojan_BAT_RapidStealer_A_dha{
	meta:
		description = "Trojan:BAT/RapidStealer.A!dha,SIGNATURE_TYPE_PEHSTR,1d 00 1d 00 1d 00 00 "
		
	strings :
		$a_01_0 = {53 74 65 61 6c 65 72 2e 65 78 65 } //1 Stealer.exe
		$a_01_1 = {53 74 65 61 6c 65 72 2e 42 72 6f 77 73 65 72 } //1 Stealer.Browser
		$a_01_2 = {53 74 65 61 6c 65 72 2e 43 6f 6d 6d 6f 6e } //1 Stealer.Common
		$a_01_3 = {53 74 65 61 6c 65 72 2e 43 6f 6d 6d 75 6e 69 63 61 74 6f 72 } //1 Stealer.Communicator
		$a_01_4 = {53 74 65 61 6c 65 72 2e 43 6f 6d 70 72 65 73 73 69 6f 6e } //1 Stealer.Compression
		$a_01_5 = {53 74 65 61 6c 65 72 2e 43 6f 6e 66 69 67 4d 61 6e 61 67 65 72 } //1 Stealer.ConfigManager
		$a_01_6 = {53 74 65 61 6c 65 72 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 Stealer.Cryptography
		$a_01_7 = {53 74 65 61 6c 65 72 2e 4b 65 79 4c 6f 67 67 65 72 } //1 Stealer.KeyLogger
		$a_01_8 = {53 74 65 61 6c 65 72 2e 4d 65 73 73 65 6e 67 65 72 } //1 Stealer.Messenger
		$a_01_9 = {53 74 65 61 6c 65 72 2e 4d 6f 64 65 6c } //1 Stealer.Model
		$a_01_10 = {53 74 65 61 6c 65 72 2e 41 6e 6e 6f 74 61 74 69 6f 6e 73 } //1 Stealer.Annotations
		$a_01_11 = {53 74 65 61 6c 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Stealer.Properties
		$a_01_12 = {53 74 65 61 6c 65 72 2e 53 51 4c 69 74 65 } //1 Stealer.SQLite
		$a_01_13 = {53 74 65 61 6c 65 72 2e 53 79 73 74 65 6d 49 6e 66 6f } //1 Stealer.SystemInfo
		$a_01_14 = {53 74 65 61 6c 65 72 2e 55 70 64 61 74 65 } //1 Stealer.Update
		$a_01_15 = {5f 79 61 68 6f 6f 55 73 65 72 6e 61 6d 65 4b 65 79 } //1 _yahooUsernameKey
		$a_01_16 = {5f 79 61 68 6f 6f 50 61 73 73 77 6f 72 64 4b 65 79 } //1 _yahooPasswordKey
		$a_01_17 = {5f 79 61 68 6f 6f 53 61 76 65 50 61 73 73 77 6f 72 64 } //1 _yahooSavePassword
		$a_01_18 = {5f 79 61 68 6f 6f 52 65 67 69 73 74 72 79 4b 65 79 } //1 _yahooRegistryKey
		$a_01_19 = {5f 79 6d 73 67 41 75 74 68 4b 65 79 } //1 _ymsgAuthKey
		$a_01_20 = {5c 00 53 00 6b 00 79 00 70 00 65 00 5c 00 } //1 \Skype\
		$a_01_21 = {67 65 74 5f 53 65 72 76 65 72 55 72 6c } //1 get_ServerUrl
		$a_01_22 = {73 65 74 5f 53 65 72 76 65 72 55 72 6c } //1 set_ServerUrl
		$a_01_23 = {67 65 74 5f 55 73 65 72 6e 61 6d 65 } //1 get_Username
		$a_01_24 = {73 65 74 5f 55 73 65 72 6e 61 6d 65 } //1 set_Username
		$a_01_25 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //1 get_Password
		$a_01_26 = {73 65 74 5f 50 61 73 73 77 6f 72 64 } //1 set_Password
		$a_01_27 = {4d 6f 6e 69 74 6f 72 55 72 6c } //1 MonitorUrl
		$a_01_28 = {47 65 74 55 73 65 72 6e 61 6d 65 41 6e 64 50 61 73 73 77 6f 72 64 } //1 GetUsernameAndPassword
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1+(#a_01_27  & 1)*1+(#a_01_28  & 1)*1) >=29
 
}