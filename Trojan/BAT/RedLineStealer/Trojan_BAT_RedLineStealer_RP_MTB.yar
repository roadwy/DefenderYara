
rule Trojan_BAT_RedLineStealer_RP_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 7e 69 00 00 04 28 22 01 00 06 10 01 72 1b 05 00 70 03 72 31 05 00 70 28 7c 00 00 0a 0b 28 31 01 00 06 07 73 d7 00 00 0a 72 35 05 00 70 28 d8 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_RedLineStealer_RP_MTB_2{
	meta:
		description = "Trojan:BAT/RedLineStealer.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,27 00 27 00 27 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 54 72 61 6e 73 61 63 74 69 6f 6e 53 74 72 61 74 65 67 79 } //1 get_TransactionStrategy
		$a_01_1 = {4e 6f 74 49 6d 70 6c 65 6d 65 6e 74 65 64 45 78 63 65 70 74 69 6f 6e } //1 NotImplementedException
		$a_01_2 = {73 65 74 5f 54 72 61 6e 73 61 63 74 69 6f 6e 53 74 72 61 74 65 67 79 } //1 set_TransactionStrategy
		$a_01_3 = {67 65 74 5f 4c 61 7a 79 4c 6f 61 64 69 6e 67 } //1 get_LazyLoading
		$a_01_4 = {73 65 74 5f 4c 61 7a 79 4c 6f 61 64 69 6e 67 } //1 set_LazyLoading
		$a_01_5 = {67 65 74 5f 43 61 63 68 65 44 4c 52 } //1 get_CacheDLR
		$a_01_6 = {73 65 74 5f 43 61 63 68 65 44 4c 52 } //1 set_CacheDLR
		$a_01_7 = {67 65 74 5f 49 73 6f 6c 61 74 65 4c 6f 61 64 69 6e 67 4f 66 4d 6f 64 75 6c 65 } //1 get_IsolateLoadingOfModule
		$a_01_8 = {73 65 74 5f 49 73 6f 6c 61 74 65 4c 6f 61 64 69 6e 67 4f 66 4d 6f 64 75 6c 65 } //1 set_IsolateLoadingOfModule
		$a_01_9 = {67 65 74 5f 4d 6f 64 75 6c 65 49 73 6f 6c 61 74 69 6f 6e 52 65 63 69 70 65 } //1 get_ModuleIsolationRecipe
		$a_01_10 = {73 65 74 5f 4d 6f 64 75 6c 65 49 73 6f 6c 61 74 69 6f 6e 52 65 63 69 70 65 } //1 set_ModuleIsolationRecipe
		$a_01_11 = {67 65 74 5f 43 61 6e 63 65 6c 49 66 43 61 6e 74 49 73 6f 6c 61 74 65 } //1 get_CancelIfCantIsolate
		$a_01_12 = {73 65 74 5f 43 61 6e 63 65 6c 49 66 43 61 6e 74 49 73 6f 6c 61 74 65 } //1 set_CancelIfCantIsolate
		$a_01_13 = {67 65 74 5f 43 74 73 } //1 get_Cts
		$a_01_14 = {73 65 74 5f 43 74 73 } //1 set_Cts
		$a_01_15 = {67 65 74 5f 4c 6f 61 64 65 72 53 79 6e 63 4c 69 6d 69 74 } //1 get_LoaderSyncLimit
		$a_01_16 = {73 65 74 5f 4c 6f 61 64 65 72 53 79 6e 63 4c 69 6d 69 74 } //1 set_LoaderSyncLimit
		$a_01_17 = {67 65 74 5f 50 65 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e } //1 get_PeImplementation
		$a_01_18 = {73 65 74 5f 50 65 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e } //1 set_PeImplementation
		$a_01_19 = {67 65 74 5f 4c 69 62 4e 61 6d 65 } //1 get_LibName
		$a_01_20 = {72 65 6d 6f 76 65 5f 43 6f 6e 76 65 6e 74 69 6f 6e 43 68 61 6e 67 65 64 } //1 remove_ConventionChanged
		$a_01_21 = {72 65 6d 6f 76 65 5f 4e 65 77 50 72 6f 63 41 64 64 72 65 73 73 } //1 remove_NewProcAddress
		$a_01_22 = {67 65 74 5f 44 79 6e 43 66 67 } //1 get_DynCfg
		$a_01_23 = {67 65 74 5f 55 73 65 43 61 6c 6c 69 6e 67 43 6f 6e 74 65 78 74 } //1 get_UseCallingContext
		$a_01_24 = {73 65 74 5f 55 73 65 43 61 6c 6c 69 6e 67 43 6f 6e 74 65 78 74 } //1 set_UseCallingContext
		$a_01_25 = {67 65 74 5f 55 73 65 42 79 52 65 66 } //1 get_UseByRef
		$a_01_26 = {73 65 74 5f 55 73 65 42 79 52 65 66 } //1 set_UseByRef
		$a_01_27 = {67 65 74 5f 54 72 61 69 6c 69 6e 67 41 72 67 73 } //1 get_TrailingArgs
		$a_01_28 = {73 65 74 5f 54 72 61 69 6c 69 6e 67 41 72 67 73 } //1 set_TrailingArgs
		$a_01_29 = {67 65 74 5f 52 65 66 4d 6f 64 69 66 69 61 62 6c 65 53 74 72 69 6e 67 42 75 66 66 65 72 } //1 get_RefModifiableStringBuffer
		$a_01_30 = {73 65 74 5f 52 65 66 4d 6f 64 69 66 69 61 62 6c 65 53 74 72 69 6e 67 42 75 66 66 65 72 } //1 set_RefModifiableStringBuffer
		$a_01_31 = {67 65 74 5f 53 69 67 6e 61 74 75 72 65 73 56 69 61 54 79 70 65 42 75 69 6c 64 65 72 } //1 get_SignaturesViaTypeBuilder
		$a_01_32 = {73 65 74 5f 53 69 67 6e 61 74 75 72 65 73 56 69 61 54 79 70 65 42 75 69 6c 64 65 72 } //1 set_SignaturesViaTypeBuilder
		$a_01_33 = {67 65 74 5f 54 72 79 45 76 61 6c 75 61 74 65 43 6f 6e 74 65 78 74 } //1 get_TryEvaluateContext
		$a_01_34 = {73 65 74 5f 54 72 79 45 76 61 6c 75 61 74 65 43 6f 6e 74 65 78 74 } //1 set_TryEvaluateContext
		$a_01_35 = {67 65 74 5f 4d 61 6e 61 67 65 4e 61 74 69 76 65 53 74 72 69 6e 67 73 } //1 get_ManageNativeStrings
		$a_01_36 = {73 65 74 5f 4d 61 6e 61 67 65 4e 61 74 69 76 65 53 74 72 69 6e 67 73 } //1 set_ManageNativeStrings
		$a_01_37 = {67 65 74 5f 42 6f 78 69 6e 67 43 6f 6e 74 72 6f 6c } //1 get_BoxingControl
		$a_01_38 = {73 65 74 5f 42 6f 78 69 6e 67 43 6f 6e 74 72 6f 6c } //1 set_BoxingControl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1+(#a_01_27  & 1)*1+(#a_01_28  & 1)*1+(#a_01_29  & 1)*1+(#a_01_30  & 1)*1+(#a_01_31  & 1)*1+(#a_01_32  & 1)*1+(#a_01_33  & 1)*1+(#a_01_34  & 1)*1+(#a_01_35  & 1)*1+(#a_01_36  & 1)*1+(#a_01_37  & 1)*1+(#a_01_38  & 1)*1) >=39
 
}